"""Verdicts for one dependency, feedback text for an AI, and automatic repair.

Verdicts, worst first:
  HALLUCINATED     the crate is not on crates.io
  NO_SUCH_VERSION  no non-yanked release matches the requirement
  VULNERABLE       the version Cargo installs today is in a RustSec vulnerability range
  OLD_FLOOR        today's install is fine, but the requirement still allows vulnerable releases
  UNMAINTAINED     an unmaintained/unsound advisory applies to the installed version
  OK
The first three are serious.
"""
from . import index, semver as sv

RANK = ["HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR", "UNMAINTAINED", "OK"]
SERIOUS = {"HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE"}


def hits(version, adv):
    return not sv.matches_any(version, adv["patched"] or []) and not sv.matches_any(version, adv["unaffected"] or [])


def usable(rel):
    return [r["num"] for r in rel if not r["yanked"] and not sv.is_prerelease(r["num"])]


class Checker:
    def __init__(self, graph, offline=False):
        self.g, self.offline = graph, offline
        self.mem = graph.memory()

    def releases(self, name):
        return index.releases(name, offline=self.offline)

    def latest_safe(self, name):
        rel = self.releases(name)
        if rel is None:
            return None
        vulns = [a for a in self.g.advisories(name) if a["kind"] == "vulnerability"]
        safe = [v for v in usable(rel) if not any(hits(v, a) for a in vulns)]
        return max(safe, key=sv.key) if safe else None

    def real_name(self, name):
        """Did-you-mean for an invented crate: '-'/'_' spelling swap, then the mistake memory."""
        for alt in (name.replace("_", "-"), name.replace("-", "_")):
            if alt != name and self.releases(alt) is not None:
                return alt
        return self.mem.get(name)

    def check(self, name, req):
        out = {"crate": name, "req": req, "verdict": "OK", "installs": None, "advisories": [], "fix": None}
        rel = self.releases(name)
        if rel is None:
            out["verdict"] = "HALLUCINATED"
            alt = self.real_name(name)
            if alt:
                out["fix"] = {"crate": alt, "req": self.latest_safe(alt)}
            return out
        try:
            allowed = [v for v in usable(rel) if sv.matches(v, req)]
        except ValueError:
            allowed = []
        advs = self.g.advisories(name)
        vulns = [a for a in advs if a["kind"] == "vulnerability"]
        if not allowed:
            out["verdict"] = "NO_SUCH_VERSION"
        else:
            installs = max(allowed, key=sv.key)
            out["installs"] = installs
            now = [a for a in vulns if hits(installs, a)]
            floor = [a for a in vulns if a not in now and any(hits(v, a) for v in allowed)]
            notes = [a for a in advs if a["kind"] in ("unmaintained", "unsound") and hits(installs, a)]
            out["verdict"] = "VULNERABLE" if now else "OLD_FLOOR" if floor else "UNMAINTAINED" if notes else "OK"
            out["advisories"] = [{k: a[k] for k in ("id", "kind", "severity", "title")} for a in (now or floor or notes)]
        if out["verdict"] in ("NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR"):
            safe = self.latest_safe(name)
            out["fix"] = {"crate": name, "req": safe} if safe else None
        return out

    def check_all(self, deps):
        return [self.check(n, r) for n, r in deps]


def feedback(results):
    """Plain-English warnings that say exactly what to use instead (guard v2 style)."""
    lines = []
    for r in results:
        v, c, fix = r["verdict"], r["crate"], r["fix"]
        use = f" Use `{fix['crate']} = \"{fix['req']}\"` instead." if fix and fix["req"] else ""
        if v == "HALLUCINATED":
            lines.append(f"- `{c}` does not exist on crates.io." + (use or " Replace it with a real, maintained crate, or remove it."))
        elif v == "NO_SUCH_VERSION":
            lines.append(f"- `{c} = \"{r['req']}\"` matches no published version." + use)
        elif v == "VULNERABLE":
            ids = ", ".join(a["id"] for a in r["advisories"])
            lines.append(f"- `{c} = \"{r['req']}\"` installs {r['installs']}, which has known vulnerabilities ({ids})." +
                         (use or " No safe version exists; pick another crate."))
        elif v == "OLD_FLOOR":
            lines.append(f"- `{c} = \"{r['req']}\"` still allows vulnerable versions." + use)
        elif v == "UNMAINTAINED":
            a = r["advisories"][0]
            lines.append(f"- `{c}` is marked {a['kind']} by RustSec ({a['id']}); prefer a maintained alternative.")
    return "\n".join(lines)


def serious(results):
    return [r for r in results if r["verdict"] in SERIOUS]
