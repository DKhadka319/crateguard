"""Parse the RustSec advisory database (https://github.com/rustsec/advisory-db) into plain dicts."""
import glob, io, os, re, tomllib, urllib.request, zipfile

ZIP_URL = "https://codeload.github.com/rustsec/advisory-db/zip/refs/heads/main"


def _severity(vector):
    if not vector:
        return "Unknown"
    try:  # optional dependency
        from cvss import CVSS3, CVSS4
        score = (CVSS4(vector).base_score if vector.startswith("CVSS:4") else CVSS3(vector).scores()[0])
    except Exception:
        return "Unknown"
    score = float(score)
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "None"


def parse(text):
    """One advisory markdown file -> dict, or None if withdrawn/unparseable."""
    m = re.search(r"```toml\n(.*?)```", text, re.S)
    if not m:
        return None
    data = tomllib.loads(m.group(1))
    adv, ver = data.get("advisory", {}), data.get("versions", {})
    if adv.get("withdrawn"):
        return None
    title = re.search(r"^# (.+)$", text[m.end():], re.M)
    return {"id": adv["id"], "crate": adv["package"], "date": str(adv.get("date", "")),
            "title": title.group(1).strip() if title else "",
            "kind": adv.get("informational", "vulnerability") or "vulnerability",
            "severity": _severity(adv.get("cvss")), "aliases": adv.get("aliases", []),
            "patched": ver.get("patched", []), "unaffected": ver.get("unaffected", []),
            "url": adv.get("url", "")}


def from_dir(path):
    """Read every crates/<name>/RUSTSEC-*.md under an advisory-db checkout."""
    files = glob.glob(os.path.join(path, "**", "RUSTSEC-*.md"), recursive=True)
    return [a for a in (parse(open(f, encoding="utf-8").read()) for f in sorted(files)) if a]


def download_latest():
    """Download the current advisory-db from GitHub and parse it (no git needed)."""
    raw = urllib.request.urlopen(urllib.request.Request(ZIP_URL, headers={"User-Agent": "crateguard"}), timeout=120).read()
    out = []
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for n in z.namelist():
            if "/crates/" in n and re.search(r"RUSTSEC-[\d-]+\.md$", n):
                a = parse(z.read(n).decode("utf-8"))
                if a:
                    out.append(a)
    return out
