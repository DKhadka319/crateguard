"""Step 2: turn the raw data into node/relationship CSV files for Neo4j.

Inputs  (data/raw/):
  rustxec_metadata.csv      the 102 RustXec vulnerabilities (from the paper's repo)
  rustsec_advisories/*.md   the matching RustSec advisory files (title, CVSS, ranges)
  cratesio.json             versions + reverse dependencies from crates.io
Output  (data/neo4j_import/): one CSV per node label / relationship type.

All semver logic (which versions are vulnerable, whether a dependency
requirement can pull in a vulnerable version) is done here, because Cypher
has no semver support. The answers are stored as properties.
"""
import csv, glob, json, os, re, tomllib
from cvss import CVSS3, CVSS4
import cargo_semver as sv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "neo4j_import")
os.makedirs(OUT, exist_ok=True)


def jlist(s):
    """RustXec stores lists as JSON-ish text, or [N/A]."""
    s = (s or "").strip()
    if s in ("", "[N/A]", "N/A"):
        return []
    try:
        return json.loads(re.sub(r",\s*\]", "]", s))
    except json.JSONDecodeError:
        return re.findall(r'"([^"]+)"', s)


def read_advisory(path):
    text = open(path).read()
    toml_src = re.search(r"```toml\n(.*?)```", text, re.S).group(1)
    data = tomllib.loads(toml_src)
    title = re.search(r"^# (.+)$", text[text.index("```", 8) + 3:], re.M)
    data["title"] = title.group(1).strip() if title else ""
    return data


def cvss_score(vector):
    """(base score, severity) for a CVSS 3.x or 4.0 vector."""
    if vector.startswith("CVSS:4"):
        c = CVSS4(vector)
        return c.base_score, c.severity
    c = CVSS3(vector)
    return c.base_score, c.severities()[0]


def write(name, header, rows):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  {name:28s} {len(rows):6d} rows")


def main():
    meta = list(csv.DictReader(open(os.path.join(RAW, "rustxec_metadata.csv"))))
    adv_files = {os.path.basename(p)[:-3]: p for p in glob.glob(os.path.join(RAW, "rustsec_advisories", "*.md"))}
    cio = json.load(open(os.path.join(RAW, "cratesio.json")))

    advisories, cats, cwes, aliases, funcs = [], set(), [], [], []
    vuln_ranges = {}  # crate -> [(advisory_id, patched, unaffected)]
    for m in meta:
        a = read_advisory(adv_files[m["id"]])
        ad, ver = a["advisory"], a.get("versions", {})
        patched, unaffected = ver.get("patched", []), ver.get("unaffected", [])
        sev = m["severity"] if m["severity"] not in ("", "[N/A]") else ""
        score = ""
        if ad.get("cvss"):
            score, cvss_sev = cvss_score(ad["cvss"])
            sev = sev or cvss_sev
        advisories.append([m["id"], m["package"], ad.get("date", m["date"]), a["title"],
                           sev or "Unknown", score, ad.get("cvss", ""), ad.get("url", m["url"]),
                           "|".join(patched), "|".join(unaffected),
                           "|".join(ad.get("keywords", jlist(m["keywords"]))), True, "vulnerability"])
        for c in (jlist(m["categories"]) or ad.get("categories", [])):  # RustXec labels, to match the paper
            cats.add((m["id"], c))
        for w in jlist(m["CWE"]):
            cwes.append([m["id"], w])
        for al in sorted(set(ad.get("aliases", []) + jlist(m["aliases"]))):
            aliases.append([m["id"], al, al.split("-")[0]])
        for fn, ranges in a.get("affected", {}).get("functions", {}).items():
            funcs.append([m["id"], fn, m["package"], "|".join(ranges)])
        vuln_ranges.setdefault(m["package"], []).append((m["id"], patched, unaffected))

    # --- every other RustSec advisory (for the AI-suggestion guard, topic A) ---
    # Not part of RustXec, so no Version nodes; the guard checks ranges itself.
    in_rustxec = {m["id"] for m in meta}
    other_crates = set()
    for path in sorted(glob.glob(os.path.join(RAW, "rustsec_all", "crates", "*", "*.md"))):
        a = read_advisory(path)
        ad, ver = a["advisory"], a.get("versions", {})
        if ad["id"] in in_rustxec or ad.get("withdrawn"):
            continue
        score, sev = "", "Unknown"
        if ad.get("cvss"):
            score, sev = cvss_score(ad["cvss"])
        advisories.append([ad["id"], ad["package"], ad["date"], a["title"], sev, score, ad.get("cvss", ""),
                           ad.get("url", ""), "|".join(ver.get("patched", [])),
                           "|".join(ver.get("unaffected", [])), "|".join(ad.get("keywords", [])),
                           False, ad.get("informational", "vulnerability")])
        for c in ad.get("categories", []):
            cats.add((ad["id"], c))
        for al in sorted(set(ad.get("aliases", []))):
            aliases.append([ad["id"], al, al.split("-")[0]])
        for fn, ranges in a.get("affected", {}).get("functions", {}).items():
            funcs.append([ad["id"], fn, ad["package"], "|".join(ranges)])
        other_crates.add(ad["package"])

    def advisories_hitting(crate, version):
        hits = []
        for aid, patched, unaffected in vuln_ranges.get(crate, []):
            if not sv.matches_any(version, patched) and not sv.matches_any(version, unaffected):
                hits.append(aid)
        return hits

    # --- Version nodes + AFFECTED_BY ---------------------------------------
    versions, affected_by, vuln_versions = [], [], {}
    for crate, vs in cio["versions"].items():
        for v in vs:
            try:
                hits = advisories_hitting(crate, v["num"])
            except ValueError:
                continue
            versions.append([f"{crate}@{v['num']}", crate, v["num"], v["yanked"],
                             sv.is_prerelease(v["num"]), v["created_at"][:10], bool(hits)])
            affected_by += [[f"{crate}@{v['num']}", h] for h in hits]
            vuln_versions.setdefault(crate, {})[v["num"]] = hits

    # --- DEPENDS_ON with exposure analysis ---------------------------------
    deps, seen, crate_names = [], set(), set(cio["crates"]) | other_crates
    for e in cio["edges"]:
        k = (e["dependent"], e["dependency"], e["kind"])
        if k in seen or e["dependent"] == e["dependency"]:
            continue
        seen.add(k)
        crate_names |= {e["dependent"], e["dependency"]}
        admits = resolves_vuln = ""
        newest = ""
        if e["dependency"] in vuln_versions:
            # versions cargo could pick: not yanked, not prerelease, satisfies req
            cands = [n for n, _ in vuln_versions[e["dependency"]].items()
                     if not sv.is_prerelease(n) and sv.matches(n, e["req"])
                     and not any(v["yanked"] for v in cio["versions"][e["dependency"]] if v["num"] == n)]
            if cands:
                newest = max(cands, key=sv.key)
                admits = any(vuln_versions[e["dependency"]][n] for n in cands)
                resolves_vuln = bool(vuln_versions[e["dependency"]][newest])
        deps.append([e["dependent"], e["dependent_version"], e["dependency"], e["req"], e["kind"],
                     e["optional"], admits, newest, resolves_vuln])

    downloads = {n: c["downloads"] for n, c in cio["crates"].items()}
    for e in cio["edges"]:
        downloads.setdefault(e["dependent"], e["dependent_downloads"])
    crates = [[n, n in vuln_ranges, n in vuln_ranges or n in other_crates, downloads.get(n, ""),
               (cio["crates"].get(n, {}).get("description") or "").strip().replace("\n", " "),
               cio["crates"].get(n, {}).get("max_stable_version") or ""] for n in sorted(crate_names)]

    print("writing", OUT)
    write("crates.csv", ["name", "in_rustxec", "has_advisory", "downloads", "description",
                         "max_stable_version"], crates)
    write("advisories.csv", ["id", "crate", "date", "title", "severity", "cvss_score", "cvss_vector",
                             "url", "patched", "unaffected", "keywords", "in_rustxec", "kind"], advisories)
    write("categories.csv", ["advisory", "category"], sorted(cats))
    write("cwes.csv", ["advisory", "cwe"], cwes)
    write("aliases.csv", ["advisory", "alias", "type"], aliases)
    write("functions.csv", ["advisory", "path", "crate", "ranges"], funcs)
    write("versions.csv", ["id", "crate", "num", "yanked", "prerelease", "released", "vulnerable"], versions)
    write("affected_by.csv", ["version", "advisory"], affected_by)
    write("depends_on.csv", ["from", "from_version", "to", "req", "kind", "optional",
                             "admits_vulnerable", "resolves_to", "resolves_vulnerable"], deps)


if __name__ == "__main__":
    main()
